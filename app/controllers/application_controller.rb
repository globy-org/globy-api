# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  include ProblemRendering  # app/controllers/concerns/problem_rendering.rb

  before_action :configure_permitted_parameters, if: :devise_controller?

  # --- JWT/認証系の共通ハンドリング（常に存在する jwt gem の例外を優先） ---

  # 期限切れ
  rescue_from JWT::ExpiredSignature do
    render_problem(
      status: 401,
      code:   "token_expired",
      title:  "Unauthorized",
      detail: "JWT has expired"
    )
  end

  # デコード失敗・署名検証失敗など
  rescue_from JWT::DecodeError, JWT::VerificationError do
    render_problem(
      status: 401,
      code:   "invalid_token",
      title:  "Unauthorized",
      detail: "JWT is invalid"
    )
  end

  # ---- ここから Warden の例外は「定義されているときだけ」登録 ----
  if defined?(Warden) && defined?(Warden::JWTAuth) && defined?(Warden::JWTAuth::Errors)
    # 失効済みトークン（revocation strategy を使っている場合）
    if defined?(Warden::JWTAuth::Errors::RevokedToken)
      rescue_from Warden::JWTAuth::Errors::RevokedToken do
        render_problem(
          status: 401,
          code:   "revoked_token",
          title:  "Unauthorized",
          detail: "JWT has been revoked"
        )
      end
    end

    # MissingToken はバージョンにより存在しないことがあるため、登録しない。
    # （Authorization ヘッダー欠如は authenticate_with_jwt! 側で検出）
  end
  # ---- Warden の例外ハンドラ終わり ----

  protected

  def configure_permitted_parameters
    devise_parameter_sanitizer.permit(:sign_up,        keys: [:name])
    devise_parameter_sanitizer.permit(:account_update, keys: [:name])
  end

  # 必要アクションで明示的に使う
  # 例) before_action :authenticate_with_jwt!, only: [:destroy]
  def authenticate_with_jwt!
    token = bearer_token
    if token.blank?
      return render_problem(
        status: 401,
        code:   "missing_token",
        title:  "Unauthorized",
        detail: "Authorization header is missing or invalid"
      )
    end
    # devise-jwt を使っていれば、この先の検証は Warden に委ねてもOK。
    # 早期検証したい場合だけ decode する。
    # payload = Warden::JWTAuth::TokenDecoder.new.call(token) if defined?(Warden::JWTAuth)
  end

  def bearer_token
    auth = request.headers["Authorization"].to_s
    auth.start_with?("Bearer ") ? auth.split(" ", 2).last : nil
  end
end
