# frozen_string_literal: true
module CookieAuth
  extend ActiveSupport::Concern

  AT_MAX_AGE = 15.minutes
  RT_MAX_AGE = 30.days

  private

  # セッションに書かずに current_user を反映
  def set_current_user_without_session(user)
    if defined?(warden) && warden
      warden.set_user(user, scope: resource_name, store: false)
    else
      sign_in(resource_name, user, store: false)
    end
    request.env['devise.skip_trackable'] = true
  rescue ActionDispatch::Request::Session::DisabledSessionError
    # セッション無効環境でも問題なし
  end

  def set_cookie(name, value, max_age:)
    return if value.blank?
    cookies[name] = {
      value: value,
      path: "/",
      max_age: max_age,
      httponly: true,
      same_site: :lax,
      secure: Rails.env.production?
    }
  end

  def clear_cookie(name)
    cookies.delete(name, path: "/")
  end

  def clear_auth_cookies!
    clear_cookie("auth_token")
    clear_cookie("access_token")
    clear_cookie("refresh_token")
  end
end
