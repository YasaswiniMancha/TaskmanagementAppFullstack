package com.example.demo.repository;

import com.example.demo.entity.PasswordHistory;
import com.example.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, Long> {
    List<PasswordHistory> findByUser(User user);

    @Transactional
    @Modifying
    @Query("DELETE FROM PasswordHistory ph WHERE ph.user = :user")
    void deleteByUser(@Param("user") User user);
}