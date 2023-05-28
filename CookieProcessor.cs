using Microsoft.Data.Sqlite;
using System.Data;
using System.Security.Cryptography;
using System.Text;

class Program {

    static string DecryptCookie(string key, string data)
    {
        byte[] master = Convert.FromBase64String(key);
        byte[] cookie = StringToByteArray(data);

        byte[] nonce = cookie[3..15];
        byte[] ciphertext = cookie[15..(cookie.Length - 16)];
        byte[] tag = cookie[(cookie.Length - 16)..(cookie.Length)];

        byte[] plaintext = new byte[ciphertext.Length];
        AesGcm aes = new AesGcm(master);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
	
    // sqlite does not support getBytes yet
    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
    static void Main(string[] args)
    {
        string path = args[0];
        string key = args[1];
        string filter = args.Length >= 3 ? $"WHERE host_key LIKE '%{args[2]}%'" : "";
        SqliteConnection db = null;
        try
        {
            db = new SqliteConnection($"Data Source={path}");
            db.Open();
        }
        catch (Exception e)
        {
            Console.WriteLine($"failed to open {path}. Error: {e.Message}");
            return;
        }

        SqliteCommand query = db.CreateCommand();
        query.CommandText = $"SELECT host_key,name,hex(encrypted_value) FROM cookies {filter};";

        SqliteDataReader reader = query.ExecuteReader();
        while (reader.Read())
        {
            Console.WriteLine($"{reader.GetString(0)}:{reader.GetString(1)}={DecryptCookie(key, reader.GetString(2))};");
        }
    }
}
