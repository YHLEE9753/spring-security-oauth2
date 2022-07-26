package com.practice.userservice.global.cache.repository;

import com.practice.userservice.global.cache.model.TemporaryMember;
import org.springframework.data.repository.CrudRepository;

public interface TemporaryMemberRedisRepo extends CrudRepository<TemporaryMember, String> {

}
