class Api::V1::EventController < ApplicationController
  def validate
    results = []
    ai_checker = AiFraudChecker.new

    sms_data.each do |sms|
      url = normalize_url(sms[:links])

      begin
        uri = URI.parse(url)
        host = uri.host

        unless host && UrlValidatorHelper.domain_exists?(host)
          results << response_payload(sms, url, true)
          next
        end

        # ---- Rule based checks ----
        rule_safe =
          UrlValidatorHelper.valid?(url) &&
          !UrlValidatorHelper.blocke_tld?(host) &&
          !UrlValidatorHelper.ip_address_url?(host) &&
          !UrlValidatorHelper.suspicious_length?(url) &&
          !UrlValidatorHelper.lookalike_domain?(host)

        final_safe = rule_safe

        if rule_safe
          ai_result = ai_checker.check(url)
          final_safe = !ai_result["is_fraud"]
        end

        LinkEvent.find_or_initialize_by(links: url).update!(
          title: sms[:title],
          time: Time.at(sms[:date].to_i / 1000),
          safe: final_safe
        )

        results << response_payload(sms, url, !final_safe)

      rescue URI::InvalidURIError
        results << response_payload(sms, sms[:links], true)
      end
    end

    render json: { results: results }
  end

  private

  def response_payload(sms, url, unsafe)
    {
      title: sms[:title],
      date: sms[:date],
      links: url,
      unsafe: unsafe
    }
  end

  def sms_data
    params.require(:SmsData).map { |item| item.permit(:title, :date, :links) }
  end

  def normalize_url(link)
    link.start_with?("http") ? link : "https://#{link}"
  end
end