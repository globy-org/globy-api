# config/initializers/devise_jwt.rb
# devise-jwt / warden-jwt-auth が検証に使う秘密鍵を、発行側と同じものに合わせる
Warden::JWTAuth.configure do |config|
  # 発行側と同じキーを最優先で使う
  config.secret = ENV['ACCESS_TOKEN_SECRET'] ||
                  (Rails.application.credentials.dig(:jwt, :access_secret) rescue nil) ||
                  Rails.application.credentials.secret_key_base
  # 署名アルゴリズム（必要に応じて変更: HS256/HS512/RS256 等）
  config.algorithm = (ENV['ACCESS_TOKEN_ALG'] || 'HS256').to_sym
end
