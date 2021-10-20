using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Stratumn.CanonicalJson;

static byte[] GetData(JToken obj, string property)
{
    var text = obj[property].ToObject<string>();

    // https://datatracker.ietf.org/doc/html/rfc4648#section-5
    var base64 = text
        .Replace('_', '/')
        .Replace('-', '+');

        return Convert.FromBase64String(base64);
}

static async Task<JObject> ReadJsonInput()
{
    using var input = Console.OpenStandardInput();
    using var text = new StreamReader(input);
    using var reader = new JsonTextReader(text);
    return await JObject.LoadAsync(reader);
}

static byte[] ComputeHash(string text)
{
    var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
    var data = encoding.GetBytes(text);

    // Assume ES256 for now, if need be we can check against the "alg" property.
    using var sha = SHA256.Create();
    return sha.ComputeHash(data);
}

static bool ValidateHash(X509Certificate2 certificate, byte[] hash, byte[] signature)
{
    var ecdsa = certificate.GetECDsaPublicKey();
    return ecdsa.VerifyHash(hash, signature);
}

static X509Certificate2 GetRoot(string name)
{
    var assembly = Assembly.GetCallingAssembly();
    using var stream = assembly.GetManifestResourceStream($"VdsNcVerify.{name}.cer");
    var data = new byte[stream.Length];
    var read = 0;
    while (read < data.Length)
    {
        read += stream.Read(data, read, (int)Math.Min(int.MaxValue, stream.Length - read));
    }
    return new X509Certificate2(data);
}

var root = await ReadJsonInput();

var sig = root["sig"];
var algorithm = sig["alg"].ToObject<string>();
var certificateData = GetData(sig, "cer");
using var x509 = new X509Certificate2(certificateData);
using var ca = GetRoot("csca_au_rs4096");

Console.WriteLine("Certificate issued to " + x509.Subject);

var chain = new X509Chain();
chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
chain.ChainPolicy.ExtraStore.Add(ca);
var signed = chain.Build(x509) && chain.ChainElements[^1].Certificate.Equals(ca);
Console.WriteLine("Certificate signed by DFAT CSCA: " + signed);

var signature = GetData(sig, "sigvl");

var messageText = root["data"].ToString(Formatting.None);
var canonicalMessage = Canonicalizer.Canonicalize(messageText);

var hash = ComputeHash(canonicalMessage); 
var result = ValidateHash(x509, hash, signature);

Console.WriteLine("Result: " + (result ? "SUCCESS" : "FAIL"));
