defmodule APISexAuthBearerTest do
  use ExUnit.Case
  doctest APISexAuthBearer

  test "greets the world" do
    assert APISexAuthBearer.hello() == :world
  end
end
