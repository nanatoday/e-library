create database ictlibrary;
use ictlibrary;
create table user(
userId int auto_increment primary key,
firstName varchar(50),
lastName varchar(50),
email varchar(60),
userPassword varchar(80));

create table books(
bookId int auto_increment primary key,
bookName varchar(50),
bookLink varchar(60),
imageUrl varchar(60),
catId int,
foreign key(catId) references category(catId));

create table category(
catId int auto_increment primary key,
catName varchar(50)
);
CREATE TABLE admin(
adminId int PRIMARY KEY AUTO_INCREMENT,
username varchar(30) not null,
email varchar(30) not null,
password varchar(80)
);