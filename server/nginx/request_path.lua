function request_path()
  local str = ngx.var.request
  local x = string.find(str, " ")
  str = string.sub(str, x+1, #str)
  x = string.find(str, " ")
  return string.sub(str, 1, x-1)
end

return request_path