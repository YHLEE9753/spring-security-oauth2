package com.practice.userservice.global.cache.repository;

import com.practice.userservice.global.cache.model.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRedisRepo extends CrudRepository<RefreshToken, String> {

}
