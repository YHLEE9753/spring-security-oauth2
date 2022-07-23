package com.practice.userservice.domain.cache.repository;

import com.practice.userservice.domain.cache.model.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRedisRepo extends CrudRepository<RefreshToken, String> {

}
