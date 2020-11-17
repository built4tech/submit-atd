<#
.SYNOPSIS
    McAfee ATD Submitter
.DESCRIPTION
    Powershell Script to submit files to McAfee ATD
    File Name : Submit-atd.ps1

    Examples of use:

       1) Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123! -Fullname C:\test\source.bin

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B
         
        2) Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123! -Fullname C:\test\source.bin, C:\test\source-2.bin

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source-2.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

        3) get-content .\input.txt | Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123!

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source-2.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

        4) Get-ChildItem -Path c:\test | Select-Object -ExpandProperty Fullname | Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123!

            sucess    : True
            file_size : 963
            mimeType  : text/plain
            md5       : 8395B77C7F7ECD46E9FC19152D3E8292
            sha1      : 63C301D38D5CF5BCA427E7CBF40F37706CBD63F7
            file_name : codecs.ps1
            detail    : Upload process sucessfull
            sha256    : A36E1FE536D1C6A38615D28D8A4A40848082DA4B0A65122D4D44220AA6056BF2

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source-2.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

            sucess    : True
            file_size : 561659
            mimeType  : application/vnd.openxmlformats-officedocument.wordprocessingml.document
            md5       : CBECAE24EEAAC476CA9F5828AABB0AB6
            sha1      : C41C619C9355A30747DFA4F9DDF25B6367CA0CCC
            file_name : source.bin
            detail    : Upload process sucessfull
            sha256    : D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

        5) Get-ChildItem -Path c:\test | Select-Object Fullname | Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123! | select-object sucess, file_name, file_size, md5

            sucess file_name    file_size md5                             
            ------ ---------    --------- ---                             
              True codecs.ps1   963       8395B77C7F7ECD46E9FC19152D3E8292
              True source-2.bin 561659    CBECAE24EEAAC476CA9F5828AABB0AB6
              True source.bin   561659    CBECAE24EEAAC476CA9F5828AABB0AB6

        6) Get-ChildItem -path c:\test | select-object @{n='Fullname'; e={$_.FullName}} | Submit-atd -Atd_host 192.168.20.140 -Atd_user admin -Atd_pass McAfee123! | select-object sucess, file_name, file_size, sha256

            sucess file_name    file_size sha256                                                          
            ------ ---------    --------- ------                                                          
              True codecs.ps1   963       A36E1FE536D1C6A38615D28D8A4A40848082DA4B0A65122D4D44220AA6056BF2
              True source-2.bin 561659    D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B
              True source.bin   561659    D66C3A184327B3E675725D1A70844B8A7653C1FD9774CC02B7C04F9FD78E909B

    Author    : Carlos Munoz <carlos_munoz@mcafee.com>, <carlos.munoz.garrido@outlook.com>

.LINK

    https://www.built4tech.com
    https://github.com/built4tech

#>

# Next function allows to work with self-signed certificates
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@


function Submit-Atd
    {
    [CmdletBinding()]
    Param
        (
        # ATD Server related parameters
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_host, 
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_user,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_pass,
        
        # Parameter related to the files that will be uploded to the ATD, Pipe allowed
        [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]] $Fullname  
        )
    Begin
        {

        # Function used during the memorystream building object, used for the multi-part header when submitting files to ATD

        function Get-AsciiBytes([String] $str) 
            {
            return [System.Text.Encoding]::ASCII.GetBytes($str)            
            }
        
        ########## Set of commands related to the connection with ATD server #########

        # Allow self-Signed certificates

        # Note: I have found many references indicating that they way to allow self signed certificates is setting to true the next policy.
        # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        # However after many tries the only way I have been able to make it work is through the class previusly defined

       
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 
          

        # Foring the system to use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

          
        # The $credentials variable will be used in the authentication header, that information must be sent in B64 format
        $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Atd_user+":"+$Atd_pass))

        # Authentication header
        $auth_header = @{
                        'Accept'       = 'application/vnd.ve.v1.0+json'
                        'Content-Type' = 'application/json'
                        'VE-SDK-API'   = $Credentials
                        };

        # Invoking the connection using the powerhsell invoke-restmethod
        $login_url = "https://${Atd_host}/php/session.php"
        try 
            {
            $response = Invoke-RestMethod -Uri $login_url -Method Get -Headers $auth_header
            }
        catch 
            {
            # If something goes wrong we break the script
            # Note: The begin section of this cmdlet is the only place where I break the script, in the Process section I don't break the script as I allow piping

            Write-Error ("Error: Connection with ATD server couldn't be made")
            $_.Exception | Format-List -Force
            break
            }
        
        # If the connection successes we get the session value and we build the session header for further communications with the ATD API
        If ($response.success)
            {
            $session  = $response.results.session
            $user_ID  = $response.results.userId
            $matd_Ver = $response.results.matdVersion
            $api_Ver  = $response.results.apiVersion

            $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($session+":"+$user_ID))

            $session_header = @{
                                'Accept'       = 'application/vnd.ve.v1.0+json'
                                 'VE-SDK-API'   = $Credentials
                               };

            # As the objective of this script is to upload files to the ATD for analysis I generate the post data in this section.
            # Generating the post data in this section avoids this part of the code to be executed multiple times.
            $post_data = @{
                          'data' = @{
                                    'data' = @{
                                            'xMode'         = '0'
                                            'skipTaskId'    = '1'
                                            'srcIp'         = ''
                                            'destIp'        = ''
                                            'messageId'     = ''
                                            'analyzeAgain'  = '1'
                                            'vmProfileList' = '0'
                                            }
                                    'filePriorityQ' = 'run_now'
                                    }
                          }
            # Later we will need this information in Json instead of a hashtable
            $post_data = $post_data | ConvertTo-Json

            }
        Else
            {
            # If something goes wrong we break the script
            # Note: The begin section of this cmdlet is the only place where I break the script, in the Process section I don't break the script as I allow piping
            Write-Error("Error: Information returned unexpected")
            break
            }

        }
    Process
        {
        $upload_url = "https://${Atd_host}/php/fileupload.php"
        $Report = @()
        foreach($file in $Fullname)
            {
		    $file_name = Split-Path $file -leaf

            # Check that the file passed as a parameter really exits and points to a file
            If (Test-Path -Path $file -PathType Leaf)
                {
                try
                    {
                    # I read the file with two objectives:
                    #  - Calculate the size of the file if it's bigger than 120 MB I avoid sumition
                    #  - If the file is smaller I will need this information during the multi-part header creation process
                    $bin_file = [System.IO.File]::ReadAllBytes($file)
                    }
                catch
                    {
                    # .NET ReadAllBytes function creates an exception if the file to read is bigger than 2 GB, so I capture the exception and I create a flag variable for further use.
                    $too_big = 1
                    }

                If ($bin_file.Length /1024 /1024 -lt 120 -And -Not ($too_big))
                    {
                    # File is smaller than 120 MB, and the 2GB exception has not been generated.
                

            
                    <# 

                    ######################################################################################################################################
                    NOTE: This code allows to get the Content Type of a file.

                      During my tests I have realized that it is not necessary to expecify correctly the Content Type during the file submition to the ATD 
                      as later on ATD will do this for every submition

                      So later on I hardcode the ContentType to application/octet-stream during the muti-part header construction.
                    ######################################################################################################################################
                    Add-Type -AssemblyName System.Web
 
                    $mimeType = [System.Web.MimeMapping]::GetMimeMapping($file)
            
                    if ($mimeType)
                    {
                        $ContentType = $mimeType
                    }
                    else
                    {
                        $ContentType = "application/octet-stream"
                    }
                    #####################################################################################################################################
                    #>
        
            		
                    # Note:
                    #   PowerShell doesn't support mutipart headers in the same way that the python requests module does, so the best way I have found is to
                    #   create a Memory Stream where the multipart header will be written and then send this memory stream in the POST request. 
                    #
                    #   McAfee ATD expects a multi-part header with two sections, the first section includes the name of the file as well as the file info
                    #   the second section includes the post-data created on the begin section of the cmdlet 

                    ############ building Multi-part header ###############

                    [byte[]]$CRLF = 13, 10

                    $body = New-Object System.IO.MemoryStream

                    $boundary = [Guid]::NewGuid().ToString().Replace('-','')
                    $ContentType = 'multipart/form-data; boundary=' + $boundary
                    $b2 = Get-AsciiBytes ('--' + $boundary)
                    $body.Write($b2, 0, $b2.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
  
                    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="amas_filename"; filename="' + $file_name + '";'))
                    $body.Write($b, 0, $b.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)            
                    $b = (Get-AsciiBytes 'Content-Type:application/octet-stream')
                    $body.Write($b, 0, $b.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
            
                    #$b = [System.IO.File]::ReadAllBytes($file) --> $bin_file previously created to calculate file size
                    $body.Write($bin_file, 0, $bin_file.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($b2, 0, $b2.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)

                    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="data"'))
                    $body.Write($b, 0, $b.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
            
                    $b = (Get-AsciiBytes $post_data)
                    $body.Write($b, 0, $b.Length)
        
                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($b2, 0, $b2.Length)
            
                    $b = (Get-AsciiBytes '--')
                    $body.Write($b, 0, $b.Length)
            
                    $body.Write($CRLF, 0, $CRLF.Length)


                    # Once the header as well as the post information arre created I invoke the invoke-restmethod cmdlet
                    #
                    # In this case, as opposite than during the  begin section, I don't break the script if something goes wrong allowing piping.
                    # I create an object instead, so typical cmdlets transformations can be done.
               

                    try 
                        {
                    $response = Invoke-RestMethod -Uri $upload_url -ContentType $ContentType -Method Post -Headers $session_header -Body $body.ToArray()
                        }
                    catch
                        {
                        Write-Error ("Error: File {$file_name} couldn't be uploaded to ATD server")
                        }

                    If ($response.success)
                        {
                        # I know I should write this in a better way, but anyway it works


                        $atd_submition = new-object psobject -property @{
                                                                  sucess    = $response.success 
                                                                  file_name = $file_name
                                                                  file_size = $response.results.size
                                                                  mimeType  = $response.mimeType
                                                                  md5       = $response.results.md5
                                                                  sha1      = $response.results.sha1
                                                                  sha256    = $response.results.sha256
                                                                  detail    = 'Upload process sucessfull'
                                                                 }
         
                        }
                    Else
                        {
                        $atd_submition = new-object psobject -property @{
                                                                  sucess    = 'False' 
                                                                  file_name = $file_name
                                                                  file_size = ''
                                                                  mimeType  = ''
                                                                  md5       = ''
                                                                  sha1      = ''
                                                                  sha256    = ''
                                                                  detail    = 'Error: Information received by ATD unexpected'
                                                                 }
                        }
                    }
                Else
                    {
                    # File is bigger than 120 MB
                    $atd_submition = new-object psobject -property @{
                                                                  sucess    = 'False' 
                                                                  file_name = $file_name
                                                                  file_size = ''
                                                                  mimeType  = ''
                                                                  md5       = ''
                                                                  sha1      = ''
                                                                  sha256    = ''
                                                                  detail    = 'Error: File bigger than permitted'
                                                                 }

                    }
           
                }
            Else
                {
                $atd_submition = new-object psobject -property @{
                                                              sucess    = 'False' 
                                                              file_name = $file_name
                                                              file_size = ''
                                                              mimeType  = ''
                                                              md5       = ''
                                                              sha1      = ''
                                                              sha256    = ''
                                                              detail    = "Error: File doesn't exist of doesn't point to a file"
                                                             }
                }
            $report += $atd_submition 
            #return $atd_submition
            }
        return $report
    }
    End
        {
        # Close the connection to ATD

        $logout_url = "https://${Atd_host}/php/session.php"
        $response = Invoke-RestMethod -Uri $logout_url -Method Delete -Headers $session_header 

        }
    }

