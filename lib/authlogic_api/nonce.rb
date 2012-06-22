module AuthlogicApi::Nonce
  extend self
  
  def validate_single_use(salt, timestamp, timeout = 600)
    t = Time.at(timestamp)
    return false if t < Time.now - timeout.seconds
    if ::Nonce.scoped(:conditions => ["timestamp >= ? AND salt = ?", Time.now - timeout.seconds, salt]).empty?
      return true if ::Nonce.create(:salt => salt, :timestamp => t)
    else
      return false
    end
  end
  
end