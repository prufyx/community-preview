if ([.[] | (.group + "/" + .plural)] | length) != ([.[] | (.group + "/" + .plural)] | unique | length) then
  error("duplicate CRD identity")
elif any(.[]; ([.versions[].name] | length) != ([.versions[].name] | unique | length)) then
  error("duplicate CRD version")
else
  sort_by([.group, .plural]) | map(.versions |= sort_by(.name))
end
