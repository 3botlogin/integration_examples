Rails.application.routes.draw do
  get 'login', to: 'threebot#login'
end

Rails.application.routes.draw do
  get 'callback', to: 'threebot#callback'
end
