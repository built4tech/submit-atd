
# Description

PowerShell cmdlet script that allows to upload files to a McAfee Advanced Threat Defense solution.

Submit-atd.ps1 ia a Powershell cmdlet that allows getting the list of files to submit via piping, lists, input files and in general using any object that can inject a full path to the subit-atd Fullname property. See Usage as a standalone tool for more information.

# Requirements

* Create an user in McAfee ATD with Restfull access and multiple login property enable
* Assign the correct profile to the user, as this profile will be the one that will be used by the Powershell cmdlet.
* The Powershell cmdlet submit-atd is not signed so be sure that the Powershell policy of the systems allows its execution.

You can check the execution policy with the command **Get-ExecutionPolicy**, its execution should show the value Unrestricted it can be changed with the command **Set-ExecutionPolicy -ExecutionPolicy Unrestricted**

## Installation as a standalone tool

* **Step 1** Clone the repository.

git clone https://github.com/built4tech/submit-atd.git

* **Step 2** Install the Powershell cmdlet as a module

import-module Submit-atd-ps1

* **Step 3** Installation done use it as a usual module. Review the Usage as a standalone tool section.

## Integration with McAfee Mvision EDR

* **Step 1** Copy the content of the custom reaction located at: 

https://github.com/built4tech/submit-atd/blob/master/reactions/mvedr_script.ps1

* **Step 2** McAfee Mvision EDR Steps:

* Logon into Mvision EDR
* Go to Menu / Catalog / Reactions
* Add a new Custom Reaction, give a name that start with _ (For instance _SendtoATD)
* Expand Windows and chose "Execute PowerShell Script" on Type
* Paste the content obtained on **Step 1** in the Content Window.
* Add the following Reaction Arguments (Don't change the names as the content previously copied expect these names)

Name|Type
---|---
atd-host|String
atd-user|String
atd-pass|String
file-path|String

* Let the timeout value to its default value

* **Step 3** Integration done, a new Custom Reaction will be available, make a Real time search, select the device and apply the new custom reaction, indicating the atd ip address, user name, password and the full path of the file to be submitted.

The result of the reaction will appear on the Action History (Menu / Action History), the column Action Status will indicate when the submition is done.

McAfee ATD will show the result of the submition.

**How it Works**

The custom reaction, downloads  atd-sumit.ps1 cmdlet from its repo and store it in a temporal location, then it imports it as a module, and finally sets the command line with the environment variables that will be passed from Mvision EDR when the reaction is executed.

## Usage as a standalone tool


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






