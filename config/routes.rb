Rails.application.routes.draw do
  # 例: /health は現状のまま
  get :health, to: 'health#show'

  devise_for :users, controllers: {
    registrations: 'users/registrations',
    sessions: 'users/sessions'
  }

  namespace :api do
    namespace :v1 do
      # 例: 現在ユーザー用エンドポイントをこのあと実装予定
      # get 'users/me', to: 'users#me'
    end
  end
end
