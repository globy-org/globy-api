class HealthController < ActionController::API
  def show
    ActiveRecord::Base.connection.execute('SELECT 1')
    render json: { ok: true }
  rescue => e
    render json: { ok: false, error: e.message }, status: :service_unavailable
  end
end
