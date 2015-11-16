package ch.rasc.eds.starter.util;

import java.util.ArrayList;
import java.util.List;

import org.bson.conversions.Bson;

import com.mongodb.client.model.Sorts;

import ch.ralscha.extdirectspring.bean.ExtDirectStoreReadRequest;
import ch.ralscha.extdirectspring.bean.SortDirection;
import ch.ralscha.extdirectspring.bean.SortInfo;

public abstract class RepositoryUtil {

	public static List<Bson> getSorts(ExtDirectStoreReadRequest request) {
		List<Bson> sorts = new ArrayList<>();
		for (SortInfo sortInfo : request.getSorters()) {

			if (sortInfo.getDirection() == SortDirection.ASCENDING) {
				sorts.add(Sorts.ascending(sortInfo.getProperty()));
			}
			else {
				sorts.add(Sorts.descending(sortInfo.getProperty()));
			}
		}		
		return sorts;
	}
	
//	public static Pageable createPageable(ExtDirectStoreReadRequest request) {
//
//		List<Order> orders = new ArrayList<>();
//		for (SortInfo sortInfo : request.getSorters()) {
//
//			if (sortInfo.getDirection() == SortDirection.ASCENDING) {
//				orders.add(new Order(Direction.ASC, sortInfo.getProperty()));
//			}
//			else {
//				orders.add(new Order(Direction.DESC, sortInfo.getProperty()));
//			}
//		}
//
//		// Ext JS pages starts with 1, Spring Data starts with 0
//		int page = Math.max(request.getPage() - 1, 0);
//
//		if (orders.isEmpty()) {
//			return new PageRequest(page, request.getLimit());
//		}
//
//		Sort sort = new Sort(orders);
//		return new PageRequest(page, request.getLimit(), sort);
//
//	}

}