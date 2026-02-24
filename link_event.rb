class LinkEvent < ApplicationRecord
  validates :title, presence: true
  validates :time, presence: true
  validates :links, presence: true

  scope :safe, -> { where(safe: true) }
  scope :unsafe, -> { where(safe: false) }
end
