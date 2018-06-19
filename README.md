
# Submit-atd.ps1
PowerShell script that allows to upload files to a McAfee ATD Box

## Usage


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

## Description

Submit-atd.ps1 ia a cmdlet that allows getting the list of files to submit via piping, lists, input files and in general using any object that can inject a full path
to the Fullname property.



