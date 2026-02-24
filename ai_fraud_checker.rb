class AiFraudChecker
  def initialize
    @client = OpenAI::Client.new(access_token: ENV["OPENAI_API_KEY"])
  end

  def check(url)
    response = @client.chat(
      parameters: {
        model: "gpt-4.1-mini",
        temperature: 0,
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity expert specialized in phishing and fraud detection."
          },
          {
            role: "user",
            content: <<~PROMPT
              Analyze this URL and decide if it is fraud or phishing.

              URL: #{url}

              Respond ONLY in valid JSON:
              {
                "is_fraud": true/false,
                "risk_level": "low" | "medium" | "high",
                "reasons": [string]
              }
            PROMPT
          }
        ]
      }
    )

    JSON.parse(response.dig("choices", 0, "message", "content"))
  rescue
    { "is_fraud" => false, "risk_level" => "low", "reasons" => [] }
  end
end
