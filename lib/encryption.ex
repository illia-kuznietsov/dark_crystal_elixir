defmodule DarkCrystalElixir.Encryption do
  @moduledoc """
  Documentation for `DarkCrystalElixir.Encryption`.

  Basically provides functions for:
    --- generating an encryption key;
    --- encrypting the message using the key;
    --- decrypting the cipher and restoring the message via provided key.
  :libsodium erlang library is used for all that. You can find info about it here:
    https://libsodium.gitbook.io/doc/
  """

  # should be 24
  @noncebytes :libsodium_crypto_secretbox.noncebytes()

  @doc """
  Generates an encryption key that is used for encrypting and decrypting messages.
  """
  def generate_encryption_key(), do: :libsodium_crypto_secretbox.keygen()

  @doc """
  Encrypts a message via the given key.
  """
  def encrypt_message(message, key) do
    nonce = :libsodium_randombytes.buf(@noncebytes)
    cipher_text = :libsodium_crypto_secretbox.easy(message, nonce, key)
    nonce <> cipher_text
  end

  @doc """
  Decrypts the message via the given key.
  """
  def decrypt_message(cipher_text, key) do
    <<nonce::binary-size(@noncebytes), rest::binary>> = cipher_text
    :libsodium_crypto_secretbox.open_easy(rest, nonce, key)
  end
end
