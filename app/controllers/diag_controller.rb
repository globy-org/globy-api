# globy-api/app/controllers/diag_controller.rb
class DiagController < ApplicationController
  def whoami
    token = cookies[:auth_token]
    decoded = nil
    begin
      decoded = try_decode(token)
    rescue => e
      # 無視
    end
    render json: {
      ok: true,
      now_utc: Time.now.utc,
      cookie_present: token.present?,
      exp_utc: decoded&.dig("exp") ? Time.at(decoded["exp"]).utc : nil,
      sub: decoded&.dig("sub")
    }
  end

  private

  def try_decode(token)
    return nil if token.blank?
    secret = Rails.application.credentials.jwt_secret_key || ENV["JWT_SECRET_KEY"]
    JWT.decode(token, secret, true, { algorithm: "HS256" }).first
  end
end
