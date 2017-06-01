using Dks.SimpleToken.Core;
using System.Web.Security;

namespace Dks.SimpleToken.Protectors
{
    /// <summary>
    /// Secure token protector that uses <seealso cref="System.Web.Security.MachineKey"/>
    /// for data encryption and decryption
    /// </summary>
    public class MachineKeySecureTokenProtector : ISecureTokenProtector
    {
        private const string DefaultPurpose = "Authentication SecureToken";

        public string Purpose { get; }
        /// <summary>
        /// Constructs an instance using the provided purpose or the default one if null.
        /// </summary>
        public MachineKeySecureTokenProtector(string purpose = null)
        {
            Purpose = purpose ?? DefaultPurpose;
        }

        public byte[] ProtectData(byte[] unprotectedData)
        {
            return MachineKey.Protect(unprotectedData, Purpose);
        }

        public byte[] UnprotectData(byte[] protectedData)
        {
            return MachineKey.Unprotect(protectedData, Purpose);
        }
    }
}
