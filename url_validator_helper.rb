require "uri"
require 'resolv'

module UrlValidatorHelper

  BLOCKED_TLDS = %w[.xyz .top .click .zip .tk .ml]

  module_function

  def domain_exists?(host)
    return false if host.blank?
    Resolv.getaddress(host)
    true
  rescue Resolv::ResolvError
    false
  end

  def valid?(url)
    uri = URI.parse(url)
    uri.is_a?(URI::HTTPS) && uri.host.present?
  rescue URI::InvalidURIError
    false
  end

  # This is for blocking phising mail links which are used raw ip address
  def ip_address_url?(host)
    return false if host.blank?
    host =~ /\A\d{1,3}(\.\d{1,3}){3}\z/
  end

  # check the length of url
  def suspicious_length?(url)
    url.length > 200
  end

  # Fraud link( homograph domains )
  def lookalike_domain?(host)
    return false if host.blank?
    host.match?(/[0-9]|[^\x00-\x7F]/)
  end

  def blocke_tld?(host)
    return false if host.blank?
    tld = extract_tld(host)
    tld.present? && BLOCKED_TLDS.include?(tld)
  end

  def extract_tld(host)
    return nil if host.blank?
    return nil if host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)

    parts = host.split(".")
    return nil if parts.length < 2
    ".#{parts.last.downcase}"
  end
end