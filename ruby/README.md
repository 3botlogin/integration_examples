# README

An example for 3bot login with Ruby/Rails

* Ruby version

* System dependencies
  - ``apt install libsodium-dev``

* Configuration
  - `rails db:setup`
  - `rails db:migrat`
  - `bundle install`
 
  
* Run
  - `rails s -p 9000`

key : Base64.encode64(RbNaCl::SigningKey.generate.to_s)
 
jKeVW6/Cgpey7CCqhSkgrfNDoj+nNsh0ExdhmEnWa6A=\n