package main

import (
	"golang.org/x/crypto/scrypt"

	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

func checkErr(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(127)
	}
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UsersConfig struct {
	Users []User `json:"users"`
}

func main() {
	users := &UsersConfig{}
	fd, err := os.Open("users.json")
	checkErr(err)
	b, err := ioutil.ReadAll(fd)
	checkErr(err)
	if len(b) == 0 {
		fmt.Println("Users file was empty; initializing...")
		fd.Close()
		fd, err = os.OpenFile("users.json", os.O_WRONLY, 666)
		emptyTemplate := `{
			"users": []
		}`
		_, err := fmt.Fprint(fd, emptyTemplate)
		checkErr(err)
		b = []byte(emptyTemplate)
	}
	err = json.Unmarshal(b, users)
	checkErr(err)

	fmt.Println("=============")
	for _, u := range users.Users {
		fmt.Println("=>", u.Username)
	}
	fmt.Println("=============")

	u := &User{}
	fmt.Printf("Username: ")
	fmt.Scanln(&u.Username)
	fmt.Printf("Password: ")
	fmt.Scanln(&u.Password)

	salt := []byte("pjsalt")
	dk, err := scrypt.Key([]byte(u.Password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	u.Password = base64.StdEncoding.EncodeToString(dk)
	users.Users = append(users.Users, *u)

	b, err = json.MarshalIndent(users, "", "	")
	checkErr(err)
	fd.Close()
	fd, err = os.OpenFile("users.json", os.O_WRONLY, 666)
	checkErr(err)
	_, err = fd.Write(b)
	checkErr(err)
}
