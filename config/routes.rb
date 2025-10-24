# config/routes.rb
Rails.application.routes.draw do
  # ヘルスチェック
  get :health, to: 'health#show'

  # ─────────────────────────────────────────────────────────────
  # Devise（サーバーレンダリング/管理画面などで使用）
  #   - /users/sign_in, /users/sign_out などは従来どおり残す
  #   - SPA/BFF 向けの API は下の /auth/* に集約する
  # ─────────────────────────────────────────────────────────────
  devise_for :users, controllers: {
    registrations: 'users/registrations',
    sessions: 'users/sessions'
  }

  devise_scope :user do
    # 認証状態を返す簡易エンドポイント（現状維持）
    get '/me', to: 'users/sessions#me'
  end

  # ─────────────────────────────────────────────────────────────
  # ===================== ROUTES_START:auth_api =====================
  # BFF/SPA 向け API 認証フロー（JWT: auth_token + refresh_token）
  # ここは Auth::* に統一する（Users::* を呼ばない）
  namespace :auth do
    # ログイン: JWTペアを発行（Auth::SessionsController#create）
    post :login,   to: 'sessions#create'

    # リフレッシュ: refresh_token 検証→ローテーション（Auth::RefreshesController#create）
    post :refresh, to: 'refreshes#create'

    # サインアウト: 現在端末の refresh_token を失効し Cookie を削除（Auth::SessionsController#sign_out）
    post :sign_out, to: 'sessions#sign_out'

    # 全端末ログアウト: すべての refresh_token を失効（Auth::SessionsController#revoke_all）
    post :revoke_all, to: 'sessions#revoke_all'

    # 診断（任意）：/auth/diag/whoami
    get  'diag/whoami', to: 'diag#whoami'
  end
  # ===================== ROUTES_END:auth_api =======================
  # ─────────────────────────────────────────────────────────────

  # 将来用のAPIネームスペース（現状のまま）
  namespace :api do
    namespace :v1 do
      # get 'users/me', to: 'users#me'
    end
  end
end
