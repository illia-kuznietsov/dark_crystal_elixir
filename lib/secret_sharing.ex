defmodule DarkCrystalElixir.SecretSharing do
  @moduledoc """
  Documentation for `DarkCrystalElixir.SecretSharing`.

  Basically provides functions for:
    --- hiding a given secret in multiple shares, which provides an additional layer of data protection ;
    --- restoring the secret if given enough shares;

  KeyX library is used here. You can find info about it here:
    https://hexdocs.pm/keyx/api-reference.html
  """
  defguard amount_constraints(amount) when amount > 1 and amount < 256
  defguard secret_constraints(secret) when is_binary(secret) and byte_size(secret) == 32
  defguard threshold_constraint(threshold, amount) when threshold <= amount

  defguard constraints(secret, amount, threshold)
           when amount_constraints(amount) and secret_constraints(secret) and
                  threshold_constraint(threshold, amount)

  @doc """
  Generates random shares out of given secret. The total amount of shares should be no more than 255.
  Threshold is a property, that indicates how many of the shares should be enough for restoring the secret.
  Threshold must be smaller than total amount.
  """
  def hide_secret_in_shares(secret, amount, threshold)
      when constraints(secret, amount, threshold) do
    KeyX.generate_shares!(threshold, 255, secret)
    |> Enum.shuffle()
    |> Enum.reduce_while([], fn share, acc ->
      if length(acc) < amount, do: {:cont, [share | acc]}, else: {:halt, acc}
    end)
  end

  @doc """
  Restores the secret if the function is given enough shares.
  """
  def recover_secret_from_shares(shares), do: KeyX.recover_secret!(shares)
end
