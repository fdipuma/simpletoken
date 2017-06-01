// (C) 2017 Federico Dipuma - Dynacode
namespace Dks.SimpleToken.Core
{
    /// <summary>
    /// Generic interface for encrypting and protecting secure token data
    /// </summary>
    public interface ISecureTokenProtector
    {
        /// <summary>
        /// Protects the byte array provided using an encryption algorithm
        /// </summary>
        /// <param name="unprotectedData">Plain text or unprotected data</param>
        /// <returns>Byte array of protected data</returns>
        byte[] ProtectData(byte[] unprotectedData);

        /// <summary>
        /// Unprotects the byte array provided using the same encryption algorithm
        /// </summary>
        /// <param name="protectedData">Encrypted data</param>
        /// <returns>Byte array of unprotected data</returns>
        byte[] UnprotectData(byte[] protectedData);
    }
}
