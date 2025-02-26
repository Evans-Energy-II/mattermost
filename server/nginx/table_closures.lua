local table_closures = {}

function table_closures.get(tbl)
  local i = 0
  return function()
    i = i + 1
    return tbl[i]
  end
end

return table_closures
