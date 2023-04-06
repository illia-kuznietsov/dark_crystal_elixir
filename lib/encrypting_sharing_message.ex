defmodule DarkCrystalElixir.EncryptingSharingMessage do
  @moduledoc """
  Documentation for `DarkCrystalElixir.EncryptingSharingMessage`.
  Basically provides functions for:
    --- given a message, generates a key to then encrypt it, and then hiding a key in many secret shares;
    --- given enough shares, decrypts the message via restored key.
  For references, check out DarkCrystalElixir.Encryption and DarkCrystalElixir.SecretSharing modules.
  """

  import DarkCrystalElixir.Encryption
  import DarkCrystalElixir.SecretSharing

  # for proper work of thingz
  @share_size 33

  @doc """
  Generates an encryption key which is then passed into encryption function for the message. After that, hides the secret
  in many shares with a specified threshold for further restoration.
  In the end, each share is concatenated with the encrypted message.
  """
  def encrypt_and_share_message(message, amount, threshold) do
    key = generate_encryption_key()
    encrypted_message = encrypt_message(message, key)

    key
    |> hide_secret_in_shares(amount, threshold)
    |> Enum.map(fn share -> share <> encrypted_message end)
  end

  @doc """
  Retrieves shares from the share|encrypted-message structures, as well as the encrypted message itself.
  Shares are then passed into the function to restore the key, which in the end is used to decrypt the message.
  """
  def restore_message_from_shares(packed_shares) do
    {shares, encrypted} =
      packed_shares
      |> Enum.map_reduce(%{message: "placeholder"}, fn <<share::binary-size(@share_size),
                                                         message::binary>>,
                                                       acc ->
        {share, %{acc | message: message}}
      end)

    shares |> recover_secret_from_shares() |> then(&decrypt_message(encrypted.message, &1))
  end
end
