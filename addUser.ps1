Import-Module ActiveDirectory
$GroupInstance = Get-ADGroup -Identity "Domain Users"
$GroupArray = @()
$Users = Import-Csv -Path ".\data.csv"  
foreach ($User in $Users)
{
    $Password = $User.password + "$$@DCabco"
    $Detailedname = $User.firstname + " " + $User.name
	$Email = $User.firstname + "." + $User.name + "@scorpions.tn"
    $UserFirstname = $User.firstname
    $FirstLetterName = $User.name.substring(0,1)
    $SAM =  $FirstLetterName + $User.firstname
	$Group = $User.group
    New-ADUser -Name $Detailedname -SamAccountName $SAM -EmailAddress $Email -UserPrincipalName $SAM -DisplayName $Detailedname -GivenName $user.firstname -Surname $user.name -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $true
	if (-Not ($GroupArray -contains $Group))
    {
        New-ADGroup -Name $Group -SamAccountName $Group -DisplayName $Group -Instance $GroupInstance -GroupScope Global -GroupCategory Security
        $GroupArray += ,$Group
    }
	Add-ADGroupMember $Group $SAM
}
