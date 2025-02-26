request_path = require("request_path")

function get_redirect_path()
  local path = request_path()
  local params = ngx.req.get_uri_args()
  local query = "?redirect=" .. path

  for k,v in pairs(params) do
    query = query .. k .. "=" .. v .. "&"
  end
            
  --print(query)
  return query
end

return get_redirect_path