package com.example.demo.repository;

import com.example.demo.entity.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface TaskRepository extends JpaRepository<Task, Long> {
    List<Task> findByUserId(Long userId);
    List<Task> findByUserIdOrderByModifiedAtDesc(Long user_id);
    List<Task> findByUserIdOrderByModifiedAtAsc(Long user_id);
    List<Task> findByUserIdOrderByTitleAsc(Long user_id);
    List<Task> findByUserIdOrderByTitleDesc(Long user_id);
}