# frozen_string_literal: true
module TokenExtraction
  extend ActiveSupport::Concern

  private

  # Authorization / Header / Cookie から可能な限り access_token を取り出す
  def extract_any_access_token
    bt = bearer_token
    return bt if bt.present?

    x = request.headers["X-Auth-Token"].presence
    return x if x.present?

    %w[auth_token access_token jwt token].each do |name|
      v = cookies.signed[name] || cookies[name]
      return v if v.present?
    end
    nil
  end

  def bearer_token
    auth = request.headers["Authorization"].to_s
    auth.start_with?("Bearer ") ? auth.split(" ", 2).last : nil
  end
end
