package com.practice.userservice.domain.cache.repository;

import com.practice.userservice.domain.cache.model.SignupKey;
import org.springframework.data.repository.CrudRepository;

public interface SignupKeyRedisRepo extends CrudRepository<SignupKey, String> {

}
