package com.example.demo.controller;

import com.example.demo.entity.Task;
import com.example.demo.entity.User;
import com.example.demo.repository.TaskRepository;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {

    @Autowired
    private TaskRepository taskRepository;

    @Autowired
    private UserRepository userRepository;


    @GetMapping
    public List<Task> getTasks(@RequestParam(name = "sort", defaultValue = "modifiedAtDesc") String sort) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Fetching tasks for user: " + username + ", sort: " + sort); // Debug
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    System.out.println("User not found: " + username);
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username);
                });
        List<Task> tasks;
        switch (sort) {
            case "modifiedAtAsc":
                tasks = taskRepository.findByUserIdOrderByModifiedAtAsc(user.getUser_id());
                break;
            case "titleAsc":
                tasks = taskRepository.findByUserIdOrderByTitleAsc(user.getUser_id());
                break;
            case "titleDesc":
                tasks = taskRepository.findByUserIdOrderByTitleDesc(user.getUser_id());
                break;
            case "modifiedAtDesc":
            default:
                tasks = taskRepository.findByUserIdOrderByModifiedAtDesc(user.getUser_id());
                break;
        }
        System.out.println("Tasks found: " + tasks.size());
        return tasks;
    }

    @PostMapping
    public Task createTask(@RequestBody Task task) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Creating task for user: " + username + ", title: " + task.getTitle());
        if (task.getTitle() == null || task.getTitle().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Task title is required");
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    System.out.println("User not found: " + username);
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username);
                });
        task.setUser(user);
        task.setModifiedAt(LocalDateTime.now());
        try {
            Task savedTask = taskRepository.save(task);
            System.out.println("Task saved with ID: " + savedTask.getId());
            return savedTask;
        } catch (Exception e) {
            System.out.println("Failed to save task: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to save task: " + e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public Task updateTask(@PathVariable Long id, @RequestBody Task taskDetails) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Updating task ID: " + id + " for user: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username));
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Task not found: " + id));
        if (!task.getUser().getUser_id().equals(user.getUser_id())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Unauthorized to update this task");
        }
        task.setTitle(taskDetails.getTitle());
        task.setDescription(taskDetails.getDescription());
        task.setModifiedAt(LocalDateTime.now());
        Task updatedTask = taskRepository.save(task);
        System.out.println("Task updated: " + updatedTask.getId());
        return updatedTask;
    }

    @DeleteMapping("/{id}")
    public String deleteTask(@PathVariable Long id) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Deleting task ID: " + id + " for user: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username));
        Task task = taskRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Task not found: " + id));
        if (!task.getUser().getUser_id().equals(user.getUser_id())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Unauthorized to delete this task");
        }
        taskRepository.delete(task);
        System.out.println("Task deleted: " + id);
        return "Task deleted successfully";
    }
}