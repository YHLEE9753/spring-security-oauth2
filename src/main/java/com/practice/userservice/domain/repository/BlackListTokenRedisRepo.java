package com.practice.userservice.domain.repository;

import com.practice.userservice.domain.model.cache.BlackListToken;
import org.springframework.data.repository.CrudRepository;

public interface BlackListTokenRedisRepo  extends CrudRepository<BlackListToken, String> {

}