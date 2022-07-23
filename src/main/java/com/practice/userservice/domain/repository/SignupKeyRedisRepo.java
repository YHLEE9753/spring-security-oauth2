package com.practice.userservice.domain.repository;

import com.practice.userservice.domain.model.cache.RefreshToken;
import com.practice.userservice.domain.model.cache.SignupKey;
import org.springframework.data.repository.CrudRepository;

public interface SignupKeyRedisRepo extends CrudRepository<SignupKey, String> {

}
