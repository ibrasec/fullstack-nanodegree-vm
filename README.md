Introduction
--------------
This code is part of the fullstack nanodegree project, it is a website service programmed using Flask which is python based framework, this website shows a group of catagories, each catagory can have a group of items, where each item represents a Title and a short description
as example: the "Book" catagory can have the following items, "Learn python", "Learn English", "Maths"...etc
You can show all the items for a certain catagory, and you could create your own. this website also supports API calls and uploading item images.


File hierarchy
--------------
This repository consists of the following:

- **vagrant**: Is the main directory hosting the python code and the related web codes,files and images.

- **catalog:** This is where you could find the main application used to activate the web service using python, you will find three main folders:

- **static:** which include **img** folder that stores images to be displayed to the users

- **templates**: This is where you find html files

- **applicaiton.py**: is the file that has the python code, this is the essential code used to activate web service

- **models.py**: is the python file that is sued to defind user, item and catagory classes

- **load_catagories.py**: is the code used to load the catalog.db with some catagories if the database is empty.


Available Features
------------------
- JSON endpoint with all required content.
- The website read category and item information from a database.
- The website include a form allowing users to add new items and correctly processes these forms.
- The website include a form to update a record in the database and correctly processes this form.
- The website include a way to delete an item from the catalog.
- create, delete, and update operations consider authorization status prior to execution.
- The website implement a third party authentication and authorization service.
- There a “login” and “logout” button/link in the website.
- Added CRUD functionality for image handling.
- Implemented CSRF protection to CRUD operations.



How to use
------------

- Make sure you have virtualbox installed ( i used version 5.1.38, version 5.2 was tested 

and it doesn't work with vagrant ) 


- Download this repository to your machine simply by clicking on the download button

or by using the git command as follows:


```
 $ git clone https://github.com/ibrasec/item-catalog-vm
 $ cd item-catalog-vm/vagrant

```

- activate the vagrant then ssh into the machine using the command

```
 $ vagrant up && vagrant ssh

```

**Note:**( if you are a developer and you have an old vagrant instance), you may copy the 

downloaded repository into that instance and then execute

the above command inside that copied repository



- once you ssh to the vagrant instance, the terminal should display the following:

```
   Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-75-generic x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage

   5 packages can be updated.
   0 updates are security updates.


   The shared directory is located at /vagrant
   To access your shared files: cd /vagrant
   Last login: Fri Oct 26 18:51:50 2018 from 10.0.2.2
   vagrant@vagrant:~$ 
```

- go to the application directory and execute the python code

```
vagrant@vagrant:$ cd /vagrant/catalog
vagrant@vagrant:/vagrant/catalog$ python application.py 
 * Serving Flask app "application" (lazy loading)
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 325-904-188

```

- Now you are ready to open your browser and Enter the below url

```
    http://localhost:5000

```

 happy browsing.


Supported images
----------------
To add an item with an image, the following image extensions are supported ( png,jpeg,jpg and gif)

Any other extension is not supported

API support
--------------

The website can respond to GET requests comming from REST tools like postman or curl

-- to get all catagories and their associated items, append "catalog.json" to the localhost url as follows:
http://localhost:5000/catalog.json

This is an example of GET request using curl :

```
   curl -X GET 'http://localhost:5000/catalog.json'
```

-- to get all items associated to a certain catagory name (for example 'Books'), append
catalog/"The catagory name".json to the localhost as follows:
http://localhost:5000/catalog/<<The catagory name>>.json

This is an example of GET request using curl :

```
   curl -X GET 'http://localhost:5000/catalog/Books.json'
```

-- to get a certain item information, for example ('T-shirt' under 'Cloths' catagory),
append "catalog/"catagory name"/"item name".json to the localhost as follows:
http://localhost:5000/catalog/<<The catagory name>>/<<The item name>>.json

```
    curl -X GET 'http://localhost:5000/catalog/Cloths/T-shirt.json'

```

LICENSE
--------
ibrasec/item-catalog-vm is a repository forked from udacity 'https://github.com/udacity/fullstack-nanodegree-vm', any license applied by udacity to its main repositories applied to this. However if no license is applied, the following is the license to this repository:
ibrasec/item-catalog-vm respository is a free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ibrasec/item-catalog-vm is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

