# app/controllers/auth/refreshes_controller.rb
class Auth::RefreshesController < ApplicationController
  # refresh は未認証でも通す（authenticate_user! が未定義でも落ちないよう raise: false）
  skip_before_action :authenticate_user!, only: :create, raise: false

  # POST /auth/refresh
  def create
    # 1) Cookie から取得（本命）
    refresh_jwt = cookies["refresh_token"]

    # 2) フォールバック: Authorization: Bearer <refresh> を許容（curl検証しやすくする）
    if refresh_jwt.blank?
      auth = request.headers["Authorization"].to_s
      refresh_jwt = auth.split(" ", 2).last if auth.start_with?("Bearer ")
    end

    if refresh_jwt.blank?
      return render json: { error: "missing_refresh_token" }, status: :unauthorized
    end

    # 実装例: RefreshService で検証＆ローテーション
    unless defined?(RefreshService) && RefreshService.respond_to?(:call)
      return render json: { error: "refresh_service_not_implemented" }, status: :not_implemented
    end

    user, new_access, new_refresh, at_ttl, rt_ttl = RefreshService.call(refresh_jwt)

    unless user && new_access
      return render json: { error: "invalid_refresh_token" }, status: :unauthorized
    end

    # Cookie再発行（アクセストークンは短命、リフレッシュはローテーション）
    set_cookie("auth_token",    new_access,  max_age: (at_ttl || 15.minutes))
    set_cookie("refresh_token", new_refresh, max_age: (rt_ttl || 30.days)) if new_refresh.present?

    render json: { user: serialize_user(user) }, status: :ok
  end

  private

  def set_cookie(name, value, max_age:)
    cookies[name] = {
      value: value, path: "/", max_age: max_age,
      httponly: true, same_site: :lax,
      secure: Rails.env.production? # devはfalseでOK
    }
  end

  def serialize_user(user)
    { id: user.id, name: user.name, email: user.email }
  end
end
