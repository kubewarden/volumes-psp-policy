#!/usr/bin/env bats

@test "reject because allowedTypes is empty" {
  run kwctl run policy.wasm -r test_data/request-pod-volumes.json \
    --settings-json \
    '{ "allowedTypes": [] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*No volume type is allowed.*") -ne 0 ]
}

@test "reject because types not present" {
  run kwctl run policy.wasm -r test_data/request-pod-volumes.json \
    --settings-json \
    '{ "allowedTypes": ["foo", "hostpath"] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : ".*volume 'kube-api-access-kplj9' of type 'projected' is not in the AllowedTypes list.*") -ne 0 ]
}

@test "accept all types" {
  run kwctl run policy.wasm -r test_data/request-pod-volumes.json \
    --settings-json \
    '{ "allowedTypes": [ "*" ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept pods with no volumes" {
  run kwctl run policy.wasm -r test_data/request-pod-no-volumes.json \
    --settings-json \
    '{ "allowedTypes": [ "foo" ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}


@test "accept pods with correct types" {
  run kwctl run policy.wasm -r test_data/request-pod-volumes.json \
    --settings-json \
    '{ "allowedTypes": [ "hostPath", "projected", "foo" ] }'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
