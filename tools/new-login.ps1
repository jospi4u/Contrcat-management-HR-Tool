# Creates a login for the Aristo site.
#   powershell -ExecutionPolicy Bypass -File tools\new-login.ps1 -User hr.office
# Prints the password (give it to the person; it is not stored anywhere) and a
# line to paste into USERS in middleware.js. Only that line goes into the code:
# it holds a salted, one-way fingerprint, never the password.
param(
  [Parameter(Mandatory = $true)][string]$User,
  [string]$Password = ''
)
$Iterations = 150000

if ($Password -eq '') {
  # 16 characters, no look-alikes (0/O, 1/l/I)
  $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'.ToCharArray()
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $b = New-Object byte[] 16; $rng.GetBytes($b)
  $Password = -join ($b | ForEach-Object { $chars[$_ % $chars.Length] })
}
$salt = New-Object byte[] 16
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
$kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
$keyHex = -join ($kdf.GetBytes(32) | ForEach-Object { $_.ToString('x2') })
$sha = [Security.Cryptography.SHA256]::Create()
$fp = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($keyHex)) | ForEach-Object { $_.ToString('x2') })
$saltHex = -join ($salt | ForEach-Object { $_.ToString('x2') })

[pscustomobject]@{
  User     = $User.ToLower()
  Password = $Password
  Line     = "  '$($User.ToLower())': { salt: '$saltHex', fp: '$fp' },"
}
