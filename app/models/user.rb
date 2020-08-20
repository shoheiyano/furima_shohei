class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  has_many :items

  NAME_REGEX =  /\A[\p{katakana}\p{blank}ー－]+\z/
  alert_msg =   'はカタカナで入力して下さいィィ。'
  validates :nickname, :birthday, :first_name, :last_name, presence: true
  validates :first_name_reading, presence: true, format: { with: NAME_REGEX , message: alert_msg }
  validates :last_name_reading, presence: true, format: { with: NAME_REGEX , message: alert_msg }
  validates :password, format: { with: /\A(?=.*?[a-z])(?=.*?\d)[\w-]{8,128}+\z/i } 
end
