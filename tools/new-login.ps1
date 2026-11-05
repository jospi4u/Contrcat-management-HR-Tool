# Creates a login for the Aristo site.
#   powershell -ExecutionPolicy Bypass -File tools\new-login.ps1 -User nanda2 -Role contractor -Contractor "M/s.Nanda Enterprises"
#   powershell -ExecutionPolicy Bypass -File tools\new-login.ps1 -User pm.lacquer -Role production_manager -Division "Art of Lacquering"
# Roles: hr_admin, gm_production, production_manager, supervisor, contractor
#
# Normally you add logins in the Admin Portal (/admin) instead. This script is a fallback.
# Prints:
#   Password  give it to the person (it is not stored anywhere)
#   Line      (not used any more: logins now live in the database)
#   Sql       run in Supabase → SQL Editor to add the login
# Only salted one-way fingerprints go into the code and database, never the password.
param(
  [Parameter(Mandatory = $true)][string]$User,
  [string]$Role = 'hr_admin',
  [string]$Contractor = '',
  [string]$Division = '',
  [string]$Name = '',
  [string]$Password = ''
)
$Iterations = 150000
$User = $User.ToLower()

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

$js = { param($s) "'" + $s.Replace('\', '\\').Replace("'", "\'") + "'" }
$sq = { param($s) if ($s -eq '') { 'null' } else { "'" + $s.Replace("'", "''") + "'" } }
$extra = ", role: $(& $js $Role)"
if ($Contractor) { $extra += ", contractor: $(& $js $Contractor)" }
if ($Division)   { $extra += ", division: $(& $js $Division)" }
if ($Name)       { $extra += ", name: $(& $js $Name)" }

[pscustomobject]@{
  User     = $User
  Password = $Password
  Line     = "  '$User': { salt: '$saltHex', fp: '$fp'$extra },"
  Sql      = "insert into app_users (user_id, fp, salt, role, contractor, division, name) values ('$User', '$fp', '$saltHex', $(& $sq $Role), $(& $sq $Contractor), $(& $sq $Division), $(& $sq $Name)) on conflict (user_id) do update set fp = excluded.fp, salt = excluded.salt, role = excluded.role, contractor = excluded.contractor, division = excluded.division, name = excluded.name;"
}
