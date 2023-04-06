defmodule DarkCrystalElixirTest do
  use ExUnit.Case
  alias DarkCrystalElixir.{Encryption, SecretSharing, EncryptingSharingMessage}

  @message "The thing that is important is the thing that is not seen."

  test "basic encrypt and decrypt" do
    key = Encryption.generate_encryption_key()
    cipher_text = Encryption.encrypt_message(@message, key)

    assert String.length(cipher_text) > 0
    refute cipher_text == @message

    result = Encryption.decrypt_message(cipher_text, key)

    assert result == @message
  end

  test "fails on bad key" do
    key = Encryption.generate_encryption_key()
    cipher_text = Encryption.encrypt_message(@message, key)

    assert String.length(cipher_text) > 0
    refute cipher_text == @message

    # this would be a wrong key
    different_key = Encryption.generate_encryption_key()

    result = Encryption.decrypt_message(cipher_text, different_key)

    # result of a failed decryption is -1
    assert result == -1
  end

  test "fails on bad cipher" do
    key = Encryption.generate_encryption_key()
    cipher_text = Encryption.encrypt_message(@message, key)

    assert String.length(cipher_text) > 0
    refute cipher_text == @message

    # this would be some random bitstring
    different_cipher = :crypto.strong_rand_bytes(byte_size(cipher_text))

    result = Encryption.decrypt_message(different_cipher, key)

    # result of a failed decryption is -1
    assert result == -1
  end

  test "sharing and restoring key" do
    key = Encryption.generate_encryption_key()
    shares = SecretSharing.hide_secret_in_shares(key, 5, 4)

    result_1 = shares |> SecretSharing.recover_secret_from_shares()
    result_2 = shares |> tl() |> SecretSharing.recover_secret_from_shares()
    result_3 = shares |> tl() |> tl() |> SecretSharing.recover_secret_from_shares()

    assert result_1 == key
    assert result_2 == key
    refute result_3 == key
  end

  test "failing guards" do
    key = Encryption.generate_encryption_key()
    try do
      SecretSharing.hide_secret_in_shares(key, 4, 5)
    rescue
      e in FunctionClauseError -> e.function == :hide_secret_in_shares
    end
  end

  test "encrypting and sharing message" do
    shares = EncryptingSharingMessage.encrypt_and_share_message(@message, 5, 4)

    assert length(shares) == 5

    # passing 4 shares instead of 5 should be enough to restore key and retrieve message
    result = shares |> tl() |> EncryptingSharingMessage.restore_message_from_shares()

    assert result == @message
  end

  test "fails on bad share" do
    shares = EncryptingSharingMessage.encrypt_and_share_message(@message, 5, 4)

    assert length(shares) == 5

    # one of the shares got jumbled in the process, which should skew the key
    result =
      shares
      |> tl()
      |> List.update_at(0, &:crypto.strong_rand_bytes(byte_size(&1)))
      |> EncryptingSharingMessage.restore_message_from_shares()

    # result of a failed decryption is -1
    assert result == -1
  end

  test "fails on not enough shares" do
    shares = EncryptingSharingMessage.encrypt_and_share_message(@message, 5, 4)

    assert length(shares) == 5

    # popping too much
    result =
      shares
      |> tl()
      |> tl()
      |> EncryptingSharingMessage.restore_message_from_shares()

    # result of a failed decryption is -1
    assert result == -1
  end
end
