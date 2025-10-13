# config/routes.rb
Rails.application.routes.draw do
  # ヘルスチェック
  get :health, to: 'health#show'

  # Devise（コントローラを拡張している前提）
  devise_for :users, controllers: {
    registrations: 'users/registrations',
    sessions: 'users/sessions'
  }

  # 認証状態を返す簡易エンドポイント（現状のまま維持）
  devise_scope :user do
    get '/me', to: 'users/sessions#me'
  end

  # ← 追加: Next.js から呼ぶ sign_out（Bearer JWT を受けて失効処理）
  namespace :auth do
    post :sign_out, to: 'sessions#sign_out'
  end

  # 将来用のAPIネームスペース（現状のまま）
  namespace :api do
    namespace :v1 do
      # 例: 現在ユーザー用エンドポイントをこのあと実装予定
      # get 'users/me', to: 'users#me'
    end
  end
end
