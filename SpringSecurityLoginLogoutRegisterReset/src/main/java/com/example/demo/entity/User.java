package com.example.demo.entity;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "users_todo")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String username;
	private String password;
	private String name;
	private String phoneNumber;
	private String address;
	private String about;
	private String location;

	@ManyToOne
	@JoinColumn(name = "role_id")
	private UserRole role;

	@OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
	private List<PasswordHistory> passwordHistory = new ArrayList<>();

	public User() {
	}

	public User(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public Long getUser_id() {
		return id;
	}

	public void setUser_id(Long user_id) {
		this.id = user_id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPhoneNumber() {
		return phoneNumber;
	}

	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getAbout() {
		return about;
	}

	public void setAbout(String about) {
		this.about = about;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public UserRole getRole() {
		return role;
	}

	public void setRole(UserRole role) {
		this.role = role;
	}

	@JsonIgnore
	public List<PasswordHistory> getPasswordHistory() {
		return passwordHistory;
	}

	public void setPasswordHistory(List<PasswordHistory> passwordHistory) {
		this.passwordHistory = passwordHistory;
	}

	public void addPasswordHistory(PasswordHistory passwordHistory) {
		this.passwordHistory.add(passwordHistory);
	}

}