namespace Dks.SimpleToken.Core
{
    /// <summary>
    /// Generic interface for a secure token serializer
    /// </summary>
    public interface ISecureTokenSerializer
    {
        /// <summary>
        /// Serializes the provided token into a byte array
        /// </summary>
        /// <param name="token">Token instance to serialize</param>
        /// <returns>Byte array of serialized data</returns>
        byte[] SerializeToken(SecureToken token);

        /// <summary>
        /// Deserializes the provided byte array into a <seealso cref="SecureToken"/> object
        /// </summary>
        /// <param name="serialized">Byte array of serialized data</param>
        /// <returns>Token instance deserialized</returns>
        SecureToken DeserializeToken(byte[] serialized);
    }
}
