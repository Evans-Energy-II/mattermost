local cjson = require "cjson"
local pbkdf2 = require "resty.nettle.pbkdf2"
local session = {}
local kdf = require("resty.openssl.kdf")
local Cipher = require("resty.openssl.cipher")
local cgi = {}
local table_closures = require("table_closures")

function cgi.unescape (s)
  s = string.gsub(s, "+", " ")
  s = string.gsub(s, "%%(%x%x)", function (h)
    return string.char(tonumber(h, 16))
  end)
  return s
end

function session:new(params)
  params = params or {}
  params.mode = "aes-256-gcm"
  params.iterations = params.iterations or 1000
  params.key_length = params.key_length or 32

  setmetatable(params, self)
  self.__index = self
  return params
end

function session:decrypt_cookie()
  -- print("COOKIE KEY " .. self.cookie_key)
  local cookie = load("return ngx.var.cookie_" .. self.cookie_key)()

  -- print("------------------------------------COOKIE TYPE ", type(cookie))
  -- print('cookie ', cookie)
  if type(cookie) == "nil" then
    return 403
  end

  local cipher = assert(Cipher.new(self.mode))
  cookie = cgi.unescape(cookie)
  local data, iv, auth_tag = cookie:match("([^%-%-]+)%-%-([^%-%-]+)%-%-(.+)")

  data = ngx.decode_base64(data)
  iv = ngx.decode_base64(iv)
  auth_tag = ngx.decode_base64(auth_tag)

  if not auth_tag or #auth_tag ~= 16 then
      return nil, "Invalid auth tag"
  end

  local h = pbkdf2.hmac_sha256(self.password, self.iterations, self.salt, self  .key_length)

  local decrypted, err = cipher:decrypt(h, iv, data, false, "", auth_tag)

  if err then
    return 403
  end


  
  local cookie_payload = cjson.decode(decrypted)

  -- print('-----------------------------------------------', decrypted)
  local dec = ngx.decode_base64(cookie_payload["_rails"]["message"])
  -- print("??????????????????????????? ", dec)
  local message = cjson.decode(dec)

  return message
end

function session:is_authenticated(key)
  local decrypted_message, err = self:decrypt_cookie()

  if(decrypted_message == 403) then
    -- print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    return false
  end

  if type(decrypted_message) ~= "table" then
    return false
  end

  local id
  local _crypt

  -- warden.user.account.key":[[1],"$2a$12$YPJrHLXCSA6XGi01KqXB0O"],

  local tmp = decrypted_message[key]

  if type(tmp) == 'nil' then
    return false
  end

  for x in table_closures.get(decrypted_message[key]) do
    if type(x) == 'table' then
      for y in table_closures.get(x) do
        id = y
      end
    elseif type(x) == 'string' then
      _crypt = x
    end
  end

  if(type(id) ~= "number") then
    -- print(" ID FALSE " .. type(id))
    return false
  end

  if(type(_crypt) ~= "string") then
    -- print("CRYPT FALSE")
    return false
  end

  local session_id = decrypted_message['session_id']

  -- local created_at = decrypted_message['created_at']

  -- if(type(created_at) == 'nil') then
  --   return false
  -- end

  -- local now = os.time()

  -- if (now - created_at) > 7200 then
  --   return false
  -- end

  -- local res = assert(self.pg:query("select * from accounts where id = $1 limit 1", id))

  
  return true, key .. "_" .. id, session_id
end

return session
